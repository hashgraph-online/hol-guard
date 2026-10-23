import { r as reactExports, j as jsxRuntimeExports, A as ActionButton, s as HiMiniCheckCircle, e as HiMiniCheck, aE as HiMiniClipboard, T as Tag, R as HiMiniShieldCheck, e0 as HiMiniEllipsisHorizontal, e1 as HiMiniMinus, e2 as HiMiniWrench, d as HiMiniArrowPath, c3 as HiMiniPlus, co as HiMiniArrowTopRightOnSquare, e3 as HiMiniArrowLongRight, bS as HiMiniInformationCircle, H as HiMiniChevronRight, dX as HiMiniArrowDownTray, _ as HiMiniXMark, e4 as HiMiniArrowUpCircle, e5 as fetchReleaseFeedApi, N as EmptyState } from "../guard-dashboard.js";
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
const CHANGE_TONES = {
  security: "bg-brand-purple/10 text-brand-purple",
  added: "bg-brand-green-bg text-brand-green-text",
  changed: "bg-brand-blue/10 text-brand-blue",
  fixed: "bg-brand-attention-bg text-brand-attention",
  removed: "bg-brand-dark/[0.07] text-brand-dark/75",
  other: "bg-brand-dark/[0.07] text-brand-dark/75"
};
function changeKindTone(kind) {
  return CHANGE_TONES[kind];
}
const CHANGE_NOUNS = {
  security: "security",
  added: "added",
  changed: "changed",
  fixed: "fixed",
  removed: "removed",
  other: "other"
};
function groupChangesByKind(changes) {
  return CHANGE_ORDER.map((kind) => ({
    kind,
    label: CHANGE_LABELS[kind],
    changes: changes.filter((change) => change.kind === kind)
  })).filter((section) => section.changes.length > 0);
}
function changeCountLabel(sections) {
  return sections.map((section) => `${section.changes.length} ${CHANGE_NOUNS[section.kind]}`).join(" · ");
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
function installedStanding(index, installedVersion) {
  const label = normalizeVersionLabel((installedVersion ?? "").trim());
  if (!label) return { kind: "unknown" };
  const position = index.releases.findIndex(
    (release2) => normalizeVersionLabel(release2.versionLabel) === label
  );
  if (position === -1) return { kind: "off-page", label };
  const release = index.releases[position];
  const behind = (index.page - 1) * index.pageSize + position;
  if (behind === 0) return { kind: "current", release };
  const onOffer = (candidate) => release.channel === "preview" || candidate.channel === "stable";
  const newest = index.page === 1 ? index.releases.slice(0, position).find(onOffer) ?? null : null;
  return { kind: "behind", release, behind, newest };
}
function standingCopy(standing) {
  if (standing.kind === "unknown") {
    return {
      title: "Guard's published releases",
      body: "Every published version, what it changed, and who is verified to have changed it."
    };
  }
  if (standing.kind === "off-page") {
    return {
      title: standing.label,
      body: "This device's version is not on this page of the archive."
    };
  }
  if (standing.kind === "current") {
    return {
      title: normalizeVersionLabel(standing.release.versionLabel),
      body: `Running here, and the newest published release. Released ${formatReleaseDate(standing.release.publishedAt)}.`
    };
  }
  const count = standing.behind === 1 ? "One newer release has" : `${standing.behind} newer releases have`;
  const newest = standing.newest ? ` The newest ${channelLabel(standing.newest.channel).toLowerCase()} release is ${normalizeVersionLabel(standing.newest.versionLabel)}.` : "";
  return {
    title: normalizeVersionLabel(standing.release.versionLabel),
    body: `Running here. ${count} been published since.${newest}`
  };
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
const PULL_REQUEST_PATTERN = /#(\d{1,7})\b/g;
const TRAILING_PULL_REQUEST = /\(#(\d{1,7})\)\s*$/;
const DOCUMENTED_PREFIX = /^documented change:/i;
const MERGE_PREFIX = /^merged pull request\b/i;
const MERGE_PULL_REQUEST = /^merged pull request\s+#(\d{1,7})\b/i;
function pullRequestKey(change) {
  const fromEvidence = change.evidenceUrl?.match(/\/pull\/(\d{1,7})(?:\D|$)/);
  if (fromEvidence) return fromEvidence[1];
  const summary = change.summary.trim();
  const merge = MERGE_PULL_REQUEST.exec(summary);
  if (merge) return merge[1];
  const trailing = TRAILING_PULL_REQUEST.exec(summary);
  if (trailing) return trailing[1];
  const numbers = [...summary.matchAll(PULL_REQUEST_PATTERN)];
  return numbers.length > 0 ? numbers[numbers.length - 1][1] : null;
}
function dedupeChanges(changes, hasSourceNotes) {
  const byPullRequest = /* @__PURE__ */ new Map();
  const kept = [];
  for (const change of changes) {
    const summary = change.summary.trim();
    if (hasSourceNotes && DOCUMENTED_PREFIX.test(summary)) continue;
    const key = pullRequestKey(change);
    if (key === null) {
      kept.push(change);
      continue;
    }
    const seen = byPullRequest.get(key);
    if (seen === void 0) {
      byPullRequest.set(key, kept.length);
      kept.push(change);
      continue;
    }
    const incumbent = kept[seen];
    const incumbentIsMerge = MERGE_PREFIX.test(incumbent.summary.trim());
    const candidateIsMerge = MERGE_PREFIX.test(summary);
    if (incumbentIsMerge && !candidateIsMerge) kept[seen] = change;
    else if (incumbent.kind === "other" && change.kind !== "other" && !candidateIsMerge) {
      kept[seen] = change;
    }
  }
  return kept;
}
const ASSET_GROUPS = [
  { id: "macos", label: "macOS", test: (n) => n.includes("apple-darwin") || n.includes("macosx") },
  {
    id: "linux",
    label: "Linux",
    test: (n) => n.includes("linux")
  },
  { id: "windows", label: "Windows", test: (n) => n.includes("win_") || n.includes("windows") },
  { id: "any", label: "Any platform", test: (n) => n.includes("py3-none-any") || n.endsWith(".tar.gz") }
];
function isProvenance(name) {
  return name.includes(".attested.") || name.includes(".intoto.") || name.endsWith(".sigstore");
}
function groupReleaseAssets(assets) {
  const groups = /* @__PURE__ */ new Map();
  const provenance = [];
  const other = [];
  for (const asset of assets) {
    const name = asset.name.toLowerCase();
    if (isProvenance(name)) {
      provenance.push(asset);
      continue;
    }
    const match = ASSET_GROUPS.find((group) => group.test(name));
    if (match === void 0) {
      other.push(asset);
      continue;
    }
    const existing = groups.get(match.id);
    if (existing) existing.assets.push(asset);
    else groups.set(match.id, { id: match.id, label: match.label, assets: [asset] });
  }
  const ordered = ASSET_GROUPS.map((group) => groups.get(group.id)).filter(
    (group) => group !== void 0
  );
  if (other.length > 0) ordered.push({ id: "other", label: "Other files", assets: other });
  return { groups: ordered, provenance };
}
const MONOGRAM_TONES = [
  "bg-brand-blue/10 text-brand-blue",
  "bg-emerald-500/10 text-emerald-700",
  "bg-purple-500/10 text-purple-700",
  "bg-amber-500/10 text-amber-700",
  "bg-rose-500/10 text-rose-700",
  "bg-slate-500/10 text-slate-700"
];
function contributorMonogram(contributor) {
  const name = contributorName(contributor).replace(/^@/, "");
  const letters = name.match(new RegExp("\\p{Letter}|\\p{Number}", "gu")) ?? [];
  return (letters.slice(0, 2).join("") || "?").toUpperCase();
}
function contributorTone(contributor) {
  const seed = contributor.githubNumericId ?? 0;
  const login = contributor.login ?? "";
  let hash = Math.abs(seed);
  for (const char of login) hash = hash * 31 + char.codePointAt(0) >>> 0;
  return MONOGRAM_TONES[hash % MONOGRAM_TONES.length];
}
function groupReleasesByTrain(releases) {
  const groups = [];
  for (const release of releases) {
    const current = groups[groups.length - 1];
    if (current && current.train === release.train) current.releases.push(release);
    else groups.push({ train: release.train, releases: [release] });
  }
  return groups;
}
function mergeContributors(roster) {
  const byIdentity = /* @__PURE__ */ new Map();
  for (const contributor of roster) {
    const key = contributor.githubNumericId ? `id:${contributor.githubNumericId}` : `login:${contributor.login ?? contributor.creditId}`;
    const seen = byIdentity.get(key);
    if (!seen) {
      byIdentity.set(key, { ...contributor, roles: [...contributor.roles], credits: 1 });
      continue;
    }
    seen.credits += 1;
    for (const role of contributor.roles) {
      if (!seen.roles.includes(role)) seen.roles.push(role);
    }
    if (seen.verificationMethod !== "pull-request-author" && contributor.verificationMethod === "pull-request-author") {
      seen.verificationMethod = contributor.verificationMethod;
      if (contributor.evidenceUrl) seen.evidenceUrl = contributor.evidenceUrl;
    }
    if (!seen.login && contributor.login) {
      seen.login = contributor.login;
      if (seen.type === "unresolved") seen.type = contributor.type;
    }
    if (seen.type === "unresolved" && contributor.type !== "unresolved") seen.type = contributor.type;
    if (!seen.evidenceUrl && contributor.evidenceUrl) seen.evidenceUrl = contributor.evidenceUrl;
  }
  for (const merged of byIdentity.values()) merged.roles.sort();
  return [...byIdentity.values()].sort((a, b) => b.credits - a.credits || contributorName(a).localeCompare(contributorName(b)));
}
function nodeClass(selected, installed) {
  if (installed) return "size-2.5 bg-brand-blue ring-4 ring-brand-blue/15";
  if (selected) return "size-2.5 border-2 border-brand-blue bg-white";
  return "size-1.5 bg-brand-dark/25 group-hover:bg-brand-dark/45";
}
function ReleaseRow(props) {
  const { release } = props;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      ref: (node) => props.registerRef(release.slug, node),
      tabIndex: props.tabbable ? 0 : -1,
      "aria-current": props.selected ? "true" : void 0,
      onClick: () => props.onSelect(release.slug),
      className: `group relative flex min-h-11 w-full items-center gap-2.5 rounded-lg py-2 pl-9 pr-2.5 text-left transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none ${props.selected ? "bg-brand-blue/[0.07]" : "hover:bg-brand-dark/[0.035]"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            "aria-hidden": "true",
            className: "absolute left-4 top-1/2 flex size-4 -translate-x-1/2 -translate-y-1/2 items-center justify-center",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: `rounded-full transition-all duration-200 motion-reduce:transition-none ${nodeClass(props.selected, props.installed)}`
              }
            )
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "span",
            {
              className: `block truncate font-mono text-[13px] tabular-nums ${props.selected ? "font-semibold text-brand-dark" : "text-brand-dark/85"}`,
              children: normalizeVersionLabel(release.versionLabel)
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-0.5 block text-xs text-brand-dark/75", children: [
            formatReleaseDate(release.publishedAt),
            release.channel === "preview" ? ` · ${channelLabel(release.channel)}` : ""
          ] })
        ] }),
        props.installed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex shrink-0 items-center gap-1 rounded-full bg-brand-blue/10 px-2 py-0.5 text-[11px] font-semibold text-brand-blue", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-3.5", "aria-hidden": "true" }),
          "Installed here"
        ] }) : release.isRecommended ? (
          // The one release the publisher says to move to. Worth a mark only
          // when the reader is not already on it.
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "shrink-0 rounded-full bg-brand-green-bg px-2 py-0.5 text-[11px] font-semibold text-brand-green-text", children: "Recommended" })
        ) : null
      ]
    }
  ) });
}
function ReleaseArchiveList(props) {
  const groups = groupReleasesByTrain(props.index.releases);
  const tabbableSlug = props.selectedSlug !== null && props.index.releases.some((release) => release.slug === props.selectedSlug) ? props.selectedSlug : props.index.releases[0]?.slug ?? null;
  const rows = reactExports.useRef(/* @__PURE__ */ new Map());
  const registerRef = reactExports.useCallback((slug, node) => {
    if (node) rows.current.set(slug, node);
    else rows.current.delete(slug);
  }, []);
  const { index, selectedSlug, onSelect } = props;
  const onKeyDown = reactExports.useCallback(
    (event) => {
      const order = index.releases;
      if (order.length === 0) return;
      let origin = selectedSlug;
      for (const [slug2, node] of rows.current) {
        if (node === event.target) {
          origin = slug2;
          break;
        }
      }
      const current = order.findIndex((release) => release.slug === origin);
      let next = -1;
      if (event.key === "ArrowDown") next = Math.min(order.length - 1, current + 1);
      else if (event.key === "ArrowUp") next = Math.max(0, current <= 0 ? 0 : current - 1);
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = order.length - 1;
      else return;
      event.preventDefault();
      const slug = order[next].slug;
      if (slug !== selectedSlug) onSelect(slug, { scroll: false });
      rows.current.get(slug)?.focus();
    },
    [index.releases, selectedSlug, onSelect]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Published Guard releases", className: "flex min-h-0 flex-1 flex-col", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-h-0 flex-1 overflow-y-auto px-1.5 pb-2", onKeyDown, children: groups.map((group, position) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.train} series`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "sticky top-0 z-10 bg-white/90 px-1.5 py-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-brand-dark/75 backdrop-blur", children: group.train }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "relative space-y-0.5 pb-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            "aria-hidden": "true",
            className: "absolute inset-y-0 left-4 w-px -translate-x-1/2 bg-brand-dark/10"
          }
        ),
        group.releases.map((release) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ReleaseRow,
          {
            release,
            selected: release.slug === props.selectedSlug,
            installed: release.slug === props.installedSlug,
            tabbable: release.slug === tabbableSlug,
            onSelect: props.onSelect,
            registerRef
          },
          release.slug
        ))
      ] })
    ] }, `${group.train}-${position}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2 border-t border-brand-dark/10 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs tabular-nums text-brand-dark/75", children: pageRangeLabel(props.index) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
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
const MAX_SOURCE_CHARS = 64e3;
const MAX_BLOCKS = 1e3;
const MAX_LIST_ITEMS = 500;
const MAX_INLINE_NODES = 400;
const MAX_HREF_CHARS = 2e3;
const MAX_LIST_DEPTH = 2;
function safeHref(raw) {
  const href = raw.trim();
  if (!href || href.length > MAX_HREF_CHARS) return null;
  if (/[\u0000-\u001f\u007f\s]/.test(href)) return null;
  const lower = href.toLowerCase();
  if (!lower.startsWith("https://") && !lower.startsWith("http://")) return null;
  return href;
}
function pushText(nodes, text) {
  if (!text) return;
  const last = nodes[nodes.length - 1];
  if (last && last.kind === "text") {
    last.text += text;
    return;
  }
  nodes.push({ kind: "text", text });
}
function runLength(source, start, marker, max) {
  let length = 0;
  while (length < max && source[start + length] === marker) length += 1;
  return length;
}
function scanBudgetFor(source) {
  return { left: source.length * 4 + 1e3 };
}
function findWithin(source, token, from, budget) {
  if (budget.left <= 0) return -1;
  const found = source.indexOf(token, from);
  const scanned = (found === -1 ? source.length : found + token.length) - from;
  budget.left -= Math.max(scanned, 1);
  return budget.left < 0 ? -1 : found;
}
const WORD_CHARACTER = /[\p{L}\p{N}]/u;
function isWordCharacter(source, position) {
  if (position < 0 || position >= source.length) return false;
  return WORD_CHARACTER.test(source[position]);
}
function underscoreOpens(source, start) {
  return !isWordCharacter(source, start - 1);
}
function underscoreCloses(source, end) {
  return !isWordCharacter(source, end);
}
function parseInline(source, depth = 0, budget = scanBudgetFor(source)) {
  const nodes = [];
  let index = 0;
  let plain = "";
  const flush = () => {
    pushText(nodes, plain);
    plain = "";
  };
  while (index < source.length) {
    if (nodes.length >= MAX_INLINE_NODES) {
      plain += source.slice(index);
      break;
    }
    const char = source[index];
    if (char === "\n") {
      flush();
      nodes.push({ kind: "break" });
      index += 1;
      continue;
    }
    if (char === "\\" && index + 1 < source.length && /[\\`*_[\]()#>~]/.test(source[index + 1])) {
      plain += source[index + 1];
      index += 2;
      continue;
    }
    if (char === "`") {
      const fence = runLength(source, index, "`", 3);
      const close = findWithin(source, "`".repeat(fence), index + fence, budget);
      if (close !== -1) {
        flush();
        nodes.push({ kind: "code", text: source.slice(index + fence, close).trim() });
        index = close + fence;
        continue;
      }
    }
    if (char === "[" && depth < 3) {
      const link = readLink(source, index, depth, budget);
      if (link) {
        flush();
        nodes.push(link.node);
        index = link.next;
        continue;
      }
    }
    if ((char === "*" || char === "_") && depth < 3) {
      const marker = runLength(source, index, char, 2);
      const token = char.repeat(marker);
      let close = -1;
      if (char !== "_" || underscoreOpens(source, index)) {
        let from = index + marker;
        while (from < source.length) {
          const candidate = findWithin(source, token, from, budget);
          if (candidate === -1) break;
          if (char !== "_" || underscoreCloses(source, candidate + marker)) {
            close = candidate;
            break;
          }
          from = candidate + marker;
        }
      }
      if (close !== -1 && close > index + marker) {
        const inner = source.slice(index + marker, close);
        flush();
        nodes.push(
          marker === 2 ? { kind: "strong", children: parseInline(inner, depth + 1, budget) } : { kind: "emphasis", children: parseInline(inner, depth + 1, budget) }
        );
        index = close + marker;
        continue;
      }
    }
    if (char === "h" && source.startsWith("http", index)) {
      const bare = readBareUrl(source, index, budget);
      if (bare) {
        flush();
        nodes.push(bare.node);
        index = bare.next;
        continue;
      }
    }
    plain += char;
    index += 1;
  }
  flush();
  return nodes;
}
function readLink(source, start, depth, budget) {
  if (budget.left <= 0) return null;
  let cursor = start + 1;
  let open = 1;
  while (cursor < source.length && open > 0) {
    budget.left -= 1;
    if (budget.left < 0) return null;
    const char = source[cursor];
    if (char === "\\") {
      cursor += 2;
      continue;
    }
    if (char === "[") open += 1;
    if (char === "]") open -= 1;
    cursor += 1;
  }
  if (open !== 0 || source[cursor] !== "(") return null;
  const labelEnd = cursor - 1;
  let hrefCursor = cursor + 1;
  let parens = 1;
  while (hrefCursor < source.length && parens > 0) {
    budget.left -= 1;
    if (budget.left < 0) return null;
    const char = source[hrefCursor];
    if (char === "(") parens += 1;
    if (char === ")") parens -= 1;
    if (parens === 0) break;
    hrefCursor += 1;
  }
  if (parens !== 0) return null;
  const label = source.slice(start + 1, labelEnd);
  const href = safeHref(source.slice(cursor + 1, hrefCursor));
  const children = parseInline(label, depth + 1, budget);
  return {
    node: href ? { kind: "link", href, children } : { kind: "emphasis", children },
    next: hrefCursor + 1
  };
}
function readBareUrl(source, start, budget) {
  if (budget.left <= 0) return null;
  let end = start;
  while (end < source.length && !/[\s<>"'`)\]]/.test(source[end])) end += 1;
  budget.left -= end - start;
  while (end > start && /[.,;:!?]/.test(source[end - 1])) end -= 1;
  const href = safeHref(source.slice(start, end));
  if (!href) return null;
  return { node: { kind: "link", href, children: [{ kind: "text", text: href }] }, next: end };
}
function startsBlock(line) {
  return /^(#{1,6})\s+/.test(line) || /^\s*(?:`{3,}|~{3,})/.test(line) || /^\s*>\s?/.test(line) || /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line);
}
function listMarker(line) {
  const match = /^(\s*)(?:([-*+])|(\d{1,3})[.)])\s+(.*)$/.exec(line);
  if (!match) return null;
  return { ordered: match[3] !== void 0, indent: match[1].length, text: match[4] };
}
function parseReleaseMarkdown(source) {
  const text = source.length > MAX_SOURCE_CHARS ? source.slice(0, MAX_SOURCE_CHARS) : source;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let index = 0;
  const atLimit = () => blocks.length >= MAX_BLOCKS;
  while (index < lines.length && !atLimit()) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }
    const fence = /^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]{0,20})\s*$/.exec(line);
    if (fence) {
      const token = fence[1][0].repeat(3);
      const body = [];
      index += 1;
      while (index < lines.length && !lines[index].trimStart().startsWith(token)) {
        body.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({ kind: "code", language: fence[2] || null, text: body.join("\n") });
      continue;
    }
    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      index += 1;
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const level = Math.min(3, heading[1].length);
      blocks.push({ kind: "heading", level, children: parseInline(heading[2].trim()) });
      index += 1;
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      const quoted = [];
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
        quoted.push(lines[index].replace(/^\s*>\s?/, ""));
        index += 1;
      }
      blocks.push({ kind: "quote", children: parseInline(quoted.join("\n").trim()) });
      continue;
    }
    const marker = listMarker(line);
    if (marker) {
      const result = readList(lines, index);
      blocks.push(result.block);
      index = result.next;
      continue;
    }
    const paragraph = [lines[index].trim()];
    index += 1;
    while (index < lines.length && lines[index].trim() && !listMarker(lines[index]) && !startsBlock(lines[index])) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push({ kind: "paragraph", children: parseInline(paragraph.join("\n")) });
  }
  return blocks;
}
function readList(lines, start, depth = 0) {
  const first = listMarker(lines[start]);
  const ordered = first ? first.ordered : false;
  const baseIndent = first ? first.indent : 0;
  const items = [];
  let index = start;
  while (index < lines.length && items.length < MAX_LIST_ITEMS) {
    const line = lines[index];
    if (!line.trim()) {
      const next = lines[index + 1];
      if (!next || !listMarker(next)) break;
      index += 1;
      continue;
    }
    const marker = listMarker(line);
    if (!marker || marker.indent < baseIndent || marker.ordered !== ordered) break;
    if (marker.indent > baseIndent) {
      const parent = items[items.length - 1];
      const nested = readList(lines, index, depth + 1);
      if (parent && nested.block.kind === "list") {
        parent.items.push(...nested.block.items);
        if (parent.items.length > MAX_LIST_ITEMS) parent.items.length = MAX_LIST_ITEMS;
      } else if (nested.block.kind === "list") {
        items.push(...nested.block.items);
        if (items.length > MAX_LIST_ITEMS) items.length = MAX_LIST_ITEMS;
      }
      index = nested.next;
      continue;
    }
    const lead = [marker.text];
    index += 1;
    while (index < lines.length && lines[index].trim() && !listMarker(lines[index]) && !startsBlock(lines[index])) {
      lead.push(lines[index].trim());
      index += 1;
    }
    items.push({ children: parseInline(lead.join("\n")), items: [] });
  }
  if (depth + 1 >= MAX_LIST_DEPTH) {
    const flattened = [];
    const collect = (source) => {
      for (const item of source) {
        if (flattened.length >= MAX_LIST_ITEMS) return;
        flattened.push({ children: item.children, items: [] });
        collect(item.items);
      }
    };
    collect(items);
    return { block: { kind: "list", ordered, items: flattened }, next: index };
  }
  return { block: { kind: "list", ordered, items }, next: index };
}
function parseReleaseInline(source) {
  return parseInline(source.slice(0, MAX_SOURCE_CHARS).replace(/\r\n?/g, "\n").trim());
}
function InlineNodes({ nodes }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: nodes.map((node, position) => {
    const key = `${node.kind}-${position}`;
    switch (node.kind) {
      case "text":
        return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: node.text }, key);
      case "break":
        return /* @__PURE__ */ jsxRuntimeExports.jsx("br", {}, key);
      case "code":
        return /* @__PURE__ */ jsxRuntimeExports.jsx(
          "code",
          {
            className: "rounded-md bg-brand-dark/[0.06] px-1.5 py-0.5 font-mono text-[0.85em] text-brand-dark",
            children: node.text
          },
          key
        );
      case "strong":
        return /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "font-semibold text-brand-dark", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: node.children }) }, key);
      case "emphasis":
        return /* @__PURE__ */ jsxRuntimeExports.jsx("em", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: node.children }) }, key);
      case "link":
        return /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            href: node.href,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "rounded-sm font-medium text-brand-blue underline decoration-brand-blue/35 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: node.children })
          },
          key
        );
    }
  }) });
}
function ListItems({ items, depth }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: items.map((item, position) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "pl-1 marker:text-brand-blue/45", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: item.children }),
    item.items.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-1.5 list-[circle] space-y-1.5 pl-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListItems, { items: item.items, depth: depth + 1 }) }) : null
  ] }, position)) });
}
function CodeBlock({ block }) {
  const [copied, setCopied] = reactExports.useState(false);
  const copy = reactExports.useCallback(() => {
    void navigator.clipboard?.writeText(block.text).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    }).catch(() => {
    });
  }, [block.text]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "group/code relative my-4 overflow-hidden rounded-xl bg-brand-dark", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { className: "overflow-x-auto px-4 py-3.5 pr-14 font-mono text-[13px] leading-6 text-white/90", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: block.text }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: copy,
        className: "absolute right-2 top-2 flex size-9 items-center justify-center rounded-lg text-white/55 opacity-0 transition-opacity duration-150 hover:bg-white/10 hover:text-white focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 group-hover/code:opacity-100 motion-reduce:transition-none",
        "aria-label": copied ? "Copied" : "Copy this command",
        children: copied ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { className: "size-4 text-emerald-300", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" })
      }
    )
  ] });
}
const HEADING_CLASS = {
  1: "mt-7 text-[15px] font-semibold tracking-[-0.01em] text-brand-dark first:mt-0",
  2: "mt-6 text-sm font-semibold tracking-[-0.01em] text-brand-dark first:mt-0",
  3: "mt-5 text-sm font-semibold text-brand-dark/80 first:mt-0"
};
function Block({ block }) {
  switch (block.kind) {
    case "heading": {
      const Tag2 = block.level === 1 ? "h4" : block.level === 2 ? "h5" : "h6";
      return /* @__PURE__ */ jsxRuntimeExports.jsx(Tag2, { className: `mb-2 ${HEADING_CLASS[block.level]}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: block.children }) });
    }
    case "paragraph":
      return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "my-3 text-sm leading-6 text-brand-dark/80 first:mt-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: block.children }) });
    case "quote":
      return /* @__PURE__ */ jsxRuntimeExports.jsx("blockquote", { className: "my-4 border-l border-brand-blue/40 pl-4 text-sm italic leading-6 text-brand-dark/75", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes: block.children }) });
    case "list":
      return block.ordered ? /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "my-3 list-decimal space-y-1.5 pl-5 text-sm leading-6 text-brand-dark/80", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListItems, { items: block.items, depth: 0 }) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "my-3 list-disc space-y-1.5 pl-5 text-sm leading-6 text-brand-dark/80", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListItems, { items: block.items, depth: 0 }) });
    case "code":
      return /* @__PURE__ */ jsxRuntimeExports.jsx(CodeBlock, { block });
    case "rule":
      return /* @__PURE__ */ jsxRuntimeExports.jsx("hr", { className: "my-5 border-brand-dark/10" });
  }
}
function ReleaseNotes({ source }) {
  const blocks = reactExports.useMemo(() => parseReleaseMarkdown(source), [source]);
  if (blocks.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-w-[68ch]", children: blocks.map((block, position) => /* @__PURE__ */ jsxRuntimeExports.jsx(Block, { block }, `${block.kind}-${position}`)) });
}
function ReleaseInlineText({ source }) {
  const nodes = reactExports.useMemo(() => parseReleaseInline(source), [source]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(InlineNodes, { nodes });
}
function CoverageNote({ note }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm leading-6 text-amber-900", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-[3px] size-4 shrink-0", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: note })
  ] });
}
function Disclosure(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group rounded-xl border border-brand-dark/10 open:bg-brand-dark/[0.015]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "flex min-h-11 cursor-pointer list-none items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-dark/80 transition-colors duration-150 hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniChevronRight,
        {
          className: "size-4 shrink-0 text-brand-dark/40 transition-transform duration-200 group-open:rotate-90 motion-reduce:transition-none",
          "aria-hidden": "true"
        }
      ),
      props.summary,
      props.count === void 0 ? null : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "tabular-nums text-xs font-medium text-brand-dark/75", children: props.count })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-3 pb-4 pt-1", children: props.children })
  ] });
}
const KIND_ICONS = {
  security: HiMiniShieldCheck,
  added: HiMiniPlus,
  changed: HiMiniArrowPath,
  fixed: HiMiniWrench,
  removed: HiMiniMinus,
  other: HiMiniEllipsisHorizontal
};
function ChangeKindHeading(props) {
  const Icon = KIND_ICONS[props.kind];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: props.id, className: "flex items-center gap-2 text-sm font-semibold text-brand-dark", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: `flex size-6 shrink-0 items-center justify-center rounded-lg ${changeKindTone(props.kind)}`,
        "aria-hidden": "true",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "size-3.5" })
      }
    ),
    props.label,
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "tabular-nums text-xs font-medium text-brand-dark/75", children: props.count })
  ] });
}
function ComparisonPair({ detail }) {
  const line = comparisonLine(detail.comparison);
  if (!detail.comparison.available) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: line });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "inline-flex max-w-full items-center gap-2 rounded-lg border border-brand-dark/10 bg-surface-1 px-2.5 py-1.5 font-mono text-[13px] tabular-nums text-brand-dark/75", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: detail.comparison.predecessorRawTag }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLongRight, { className: "size-4 shrink-0 text-brand-dark/35", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate font-semibold text-brand-dark", children: detail.rawTag }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: line })
  ] });
}
function ChangeItem({ change }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-sm leading-6 text-brand-dark/80 marker:text-brand-blue/45", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(ReleaseInlineText, { source: change.summary }),
    change.evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: change.evidenceUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 rounded-sm font-medium text-brand-blue underline decoration-brand-blue/35 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none",
          children: [
            "Evidence",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-3.5", "aria-hidden": "true" })
          ]
        }
      )
    ] }) : null
  ] });
}
function ContributorChip({ contributor }) {
  const name = contributorName(contributor);
  const body = /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: `flex size-7 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums ${contributorTone(contributor)}`,
        "aria-hidden": "true",
        children: contributorMonogram(contributor)
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 truncate font-medium text-brand-dark", children: name }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "shrink-0 text-xs text-brand-dark/75", children: [
      contributor.roles.join(", "),
      contributor.credits > 1 ? ` · ${contributor.credits} changes` : null
    ] })
  ] });
  const shared = "flex min-h-11 max-w-full items-center gap-2 rounded-full border border-brand-dark/10 py-1 pl-1 pr-3 text-sm";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { title: verificationLabel(contributor.verificationMethod), children: contributor.evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    "a",
    {
      href: contributor.evidenceUrl,
      target: "_blank",
      rel: "noopener noreferrer",
      className: `${shared} transition-colors duration-150 hover:border-brand-blue/40 hover:bg-brand-blue/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none`,
      children: body
    }
  ) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: shared, children: body }) });
}
function AssetLink({ asset }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "a",
    {
      href: asset.url,
      target: "_blank",
      rel: "noopener noreferrer",
      className: "flex min-h-11 items-center gap-2 rounded-xl border border-brand-dark/10 px-3 font-mono text-[13px] text-brand-dark/80 transition-colors duration-150 hover:border-brand-blue/40 hover:bg-brand-blue/[0.04] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDownTray, { className: "size-4 shrink-0 text-brand-dark/40", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: asset.name })
      ]
    }
  ) });
}
function ReleaseDetailPanel({
  detail,
  isInstalled = false
}) {
  const notes = detail.sourceNotes;
  const notesLead = notes !== null && notes.scope === "exact_release";
  const changes = reactExports.useMemo(() => dedupeChanges(detail.changes, notesLead), [detail.changes, notesLead]);
  const sections = reactExports.useMemo(() => groupChangesByKind(changes), [changes]);
  const assets = reactExports.useMemo(() => groupReleaseAssets(detail.assets), [detail.assets]);
  const roster = reactExports.useMemo(() => mergeContributors(detail.roster), [detail.roster]);
  const note = coverageNote(detail.coverage);
  const countLabel = reactExports.useMemo(() => changeCountLabel(sections), [sections]);
  const changeList = sections.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-5", children: sections.map((section) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      "aria-labelledby": `release-changes-${section.kind}`,
      className: section.kind === "security" ? "space-y-2.5 rounded-xl border border-brand-purple/20 bg-brand-purple/[0.03] p-3 sm:p-4" : "space-y-2.5",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ChangeKindHeading,
          {
            id: `release-changes-${section.kind}`,
            kind: section.kind,
            label: section.label,
            count: section.changes.length
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "list-disc space-y-2 pl-5", children: section.changes.map((change) => /* @__PURE__ */ jsxRuntimeExports.jsx(ChangeItem, { change }, change.id)) })
      ]
    },
    section.kind
  )) }) : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      "aria-labelledby": "release-detail-heading",
      className: "guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-x-4 gap-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-1.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "h2",
                {
                  id: "release-detail-heading",
                  className: "font-mono text-[2rem] font-semibold leading-none tracking-[-0.02em] tabular-nums text-brand-dark",
                  children: normalizeVersionLabel(detail.versionLabel)
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/75", children: [
                detail.title && detail.title !== detail.rawTag ? `${detail.title} · ` : "",
                "Released ",
                formatReleaseDate(detail.publishedAt)
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: detail.channel === "stable" ? "green" : "amber", children: channelLabel(detail.channel) }),
              isInstalled ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "blue", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-3.5", "aria-hidden": "true" }),
                "Running here"
              ] }) : null
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-x-3 gap-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(ComparisonPair, { detail }),
            countLabel ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "tabular-nums text-xs text-brand-dark/75", children: countLabel }) : null
          ] })
        ] }),
        note ? /* @__PURE__ */ jsxRuntimeExports.jsx(CoverageNote, { note }) : null,
        notes !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-notes-heading", className: "space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "h3",
            {
              id: "release-notes-heading",
              className: "text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/75",
              children: notesLead ? "Published release notes" : `Release notes for the ${detail.train} series`
            }
          ),
          notesLead ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/75", children: [
            "Published for the ",
            detail.train,
            " series rather than this exact release."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ReleaseNotes, { source: notes.text })
        ] }) : null,
        notesLead || !detail.summary ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-summary-heading", className: "space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "h3",
            {
              id: "release-summary-heading",
              className: "text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/75",
              children: notes === null ? "Release notes" : "Notes for this release"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ReleaseNotes, { source: detail.summary })
        ] }),
        changeList === null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: "No itemised changes were published for this release." }) : notesLead ? /* @__PURE__ */ jsxRuntimeExports.jsx(Disclosure, { summary: "Itemised changes", count: changes.length, children: changeList }) : changeList,
        detail.roster.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-roster-heading", className: "space-y-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "release-roster-heading", className: "text-sm font-semibold text-brand-dark", children: "Verified contributors" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-wrap gap-2", children: roster.map((contributor) => /* @__PURE__ */ jsxRuntimeExports.jsx(ContributorChip, { contributor }, contributor.creditId)) })
        ] }) : null,
        detail.assets.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(Disclosure, { summary: "Downloads", count: detail.assets.length, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 pt-2", children: [
          assets.groups.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/75", children: group.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "grid gap-2 sm:grid-cols-2", children: group.assets.map((asset) => /* @__PURE__ */ jsxRuntimeExports.jsx(AssetLink, { asset }, asset.url)) })
          ] }, group.id)),
          assets.provenance.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { className: "flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/75", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-3.5", "aria-hidden": "true" }),
              "Provenance"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "grid gap-2 sm:grid-cols-2", children: assets.provenance.map((asset) => /* @__PURE__ */ jsxRuntimeExports.jsx(AssetLink, { asset }, asset.url)) })
          ] }) : null
        ] }) }) : null
      ]
    },
    detail.slug
  );
}
function Marker({ standing }) {
  if (standing.kind === "behind") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: "flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue",
        "aria-hidden": "true",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUpCircle, { className: "size-5" })
      }
    );
  }
  if (standing.kind === "current") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: "flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-green-bg text-brand-green-text",
        "aria-hidden": "true",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5" })
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      className: "flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-dark/[0.06] text-brand-dark/45",
      "aria-hidden": "true",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "size-5" })
    }
  );
}
function surfaceClass(standing) {
  if (standing.kind === "behind") return "border-brand-blue/20 bg-brand-blue/[0.04]";
  if (standing.kind === "current") return "border-brand-dark/10 bg-white";
  return "border-brand-dark/10 bg-surface-1";
}
function ReleaseStatusBand(props) {
  const { standing } = props;
  const copy = standingCopy(standing);
  const release = standing.kind === "current" || standing.kind === "behind" ? standing.release : null;
  const isVersion = release !== null || standing.kind === "off-page";
  const target = standing.kind === "behind" ? standing.newest ?? standing.release : release ?? null;
  const showCta = target !== null && props.onRead !== void 0 && props.ctaDismissed !== true;
  const ctaLabel = standing.kind === "behind" && standing.newest ? `What's new in ${normalizeVersionLabel(standing.newest.versionLabel)}` : "Read the notes";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      "aria-labelledby": "releases-standing-heading",
      className: `guard-surface-in rounded-2xl border p-4 sm:p-5 ${surfaceClass(standing)}`,
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-x-6 gap-y-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-[1_1_20rem] items-start gap-3.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Marker, { standing }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "h1",
              {
                id: "releases-standing-heading",
                className: "flex flex-wrap items-center gap-x-3 gap-y-2",
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "span",
                    {
                      className: isVersion ? "font-mono text-[1.75rem] font-semibold leading-none tracking-[-0.02em] tabular-nums text-brand-dark" : "text-xl font-semibold leading-tight tracking-[-0.01em] text-brand-dark",
                      children: copy.title
                    }
                  ),
                  release ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: release.channel === "stable" ? "green" : "amber", children: channelLabel(release.channel) }) : null
                ]
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[62ch] text-sm leading-6 text-brand-dark/75", children: copy.body })
          ] })
        ] }),
        showCta ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: props.onRead, children: ctaLabel }),
          props.onDismiss ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onDismiss,
              "aria-label": `Dismiss ${ctaLabel}`,
              className: "flex size-11 items-center justify-center rounded-xl text-brand-dark/50 transition-colors duration-150 hover:bg-brand-dark/[0.06] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5", "aria-hidden": "true" })
            }
          ) : null
        ] }) : null
      ] })
    }
  );
}
const RELEASES_PAGE_SIZE = 20;
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
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "py-8 text-center text-sm text-brand-dark/75", children: label });
}
function DetailSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      role: "status",
      "aria-label": "Reading this release",
      className: "guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-7 w-56 rounded-lg bg-brand-dark/[0.07]" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-4 w-72 rounded bg-brand-dark/[0.05]" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-w-[68ch] space-y-2.5", children: [100, 94, 88, 62].map((width) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-4 rounded bg-brand-dark/[0.05]", style: { width: `${width}%` } }, width)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-11 w-full rounded-xl bg-brand-dark/[0.04]" })
      ]
    }
  );
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
  const standing = reactExports.useMemo(
    () => indexState.kind === "ready" ? installedStanding(indexState.index, installedVersion) : { kind: "unknown" },
    [indexState, installedVersion]
  );
  const installed = standing.kind === "current" || standing.kind === "behind" ? standing.release : null;
  const handleSelect = reactExports.useCallback((slug, options) => {
    readerChose.current = true;
    setSelectedSlug(slug);
    if (options?.scroll === false) return;
    detailHeadingRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);
  const standingTarget = standing.kind === "behind" ? standing.newest ?? standing.release : standing.kind === "current" ? standing.release : null;
  const targetLabel = standingTarget?.versionLabel ?? null;
  const dismissedBefore = reactExports.useMemo(
    () => targetLabel === null ? false : isWhatsNewDismissed(targetLabel),
    [targetLabel]
  );
  const whatsNewDismissed = dismissedBefore || dismissedLabel === targetLabel;
  const handleReadWhatsNew = reactExports.useCallback(() => {
    if (standingTarget) handleSelect(standingTarget.slug);
  }, [standingTarget, handleSelect]);
  const handleDismissWhatsNew = reactExports.useCallback(() => {
    if (!targetLabel) return;
    dismissWhatsNew(targetLabel);
    setDismissedLabel(targetLabel);
  }, [targetLabel]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-releases space-y-6 pb-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ReleaseStatusBand,
      {
        standing,
        onRead: standingTarget ? handleReadWhatsNew : void 0,
        onDismiss: targetLabel ? handleDismissWhatsNew : void 0,
        ctaDismissed: whatsNewDismissed
      }
    ),
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
    indexState.kind === "ready" && indexState.index.releases.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid items-start gap-6 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex max-h-[32rem] flex-col overflow-hidden rounded-xl border border-brand-dark/10 bg-white lg:sticky lg:top-4 lg:max-h-[calc(100vh-8rem)]", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        ReleaseArchiveList,
        {
          index: indexState.index,
          selectedSlug,
          installedSlug: installed?.slug ?? null,
          onSelect: handleSelect,
          onPage: setPage
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: detailHeadingRef, className: "min-w-0", children: [
        detailState.kind === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(DetailSkeleton, {}) : null,
        detailState.kind === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          FailureNotice,
          {
            failure: detailState.failure,
            onRetry: isRetryable(detailState.failure) ? () => setDetailToken((token) => token + 1) : void 0
          }
        ) : null,
        detailState.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ReleaseDetailPanel,
          {
            detail: detailState.detail,
            isInstalled: installed?.slug === detailState.detail.slug
          }
        ) : null
      ] })
    ] }) : null
  ] });
}
export {
  ReleasesWorkspace
};
